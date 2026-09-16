rule sig_20161206_9bfc2f7d46fcb257441f2b0b295d754f {
  meta:
    description = "datamaliciousorder - file 20161206_9bfc2f7d46fcb257441f2b0b295d754f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65b8a32c1e43c0c2cf981ba7d125615ad1604b7abb9a163a5e803621fedc70bd"

  strings:
    $s1 = "var vAc0 = new Function(\"s\", '{var vZg7 = new Date();vZg7[\"setUTCFullYear\"](\"2003\");if (vZg7.getUTCFullYear().toString(10)" ascii
    $s2 = "var vAc0 = new Function(\"s\", '{var vZg7 = new Date();vZg7[\"setUTCFullYear\"](\"2003\");if (vZg7.getUTCFullYear().toString(10)" ascii
    $s3 = "function vMHj4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vDn0 = s.split(\"##\"); return vDn0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}