rule sig_20160823_326d8e5787d3b53754c6bc998adb0b05 {
  meta:
    description = "datamaliciousorder - file 20160823_326d8e5787d3b53754c6bc998adb0b05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "151f133b58637df0513f6f1b04f71f5152455eeacd417486d3ab5f4baf766fdf"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}