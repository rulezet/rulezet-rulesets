rule sig_20161207_c6a5c77d960462c0e45bb38dd599e59e {
  meta:
    description = "datamaliciousorder - file 20161207_c6a5c77d960462c0e45bb38dd599e59e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95c4b65748daac3e4403adc0545e88b7cef66adb0c42227baeb7e69457175210"

  strings:
    $s1 = "var vKXn5 = new Function(\"vZFy8\", '{var vCEj6 = new Date();vCEj6[\"setUTCFullYear\"](\"2003\");if (vCEj6.getUTCFullYear().toSt" ascii
    $s2 = "var vKXn5 = new Function(\"vZFy8\", '{var vCEj6 = new Date();vCEj6[\"setUTCFullYear\"](\"2003\");if (vCEj6.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vAy7 = vZFy8.split(\"###\"); return vAy7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vEe4 = new Function(\"vZFy8\", '{return vZFy8.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}