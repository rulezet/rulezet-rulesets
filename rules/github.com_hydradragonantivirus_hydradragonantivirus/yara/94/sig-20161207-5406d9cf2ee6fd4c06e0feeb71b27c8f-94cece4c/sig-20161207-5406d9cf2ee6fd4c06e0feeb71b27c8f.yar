rule sig_20161207_5406d9cf2ee6fd4c06e0feeb71b27c8f {
  meta:
    description = "datamaliciousorder - file 20161207_5406d9cf2ee6fd4c06e0feeb71b27c8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4f79a67bcd1d895c3110af85879d6a78df081ab0f6dc65ed00d240f02d8b32b"

  strings:
    $s1 = "var vGw1 = new Function(\"vKKh4\", '{var vYg8 = new Date();vYg8[\"setUTCFullYear\"](\"2003\");if (vYg8.getUTCFullYear().toString" ascii
    $s2 = "var vGw1 = new Function(\"vKKh4\", '{var vYg8 = new Date();vYg8[\"setUTCFullYear\"](\"2003\");if (vYg8.getUTCFullYear().toString" ascii
    $s3 = "var vTDr4 = new Function(\"vKKh4\", '{return vKKh4.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vCg4 = vKKh4.split(\"###\"); return vCg4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}