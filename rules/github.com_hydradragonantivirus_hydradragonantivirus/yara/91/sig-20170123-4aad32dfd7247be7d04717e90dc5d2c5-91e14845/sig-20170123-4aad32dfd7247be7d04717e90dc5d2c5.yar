rule sig_20170123_4aad32dfd7247be7d04717e90dc5d2c5 {
  meta:
    description = "datamaliciousorder - file 20170123_4aad32dfd7247be7d04717e90dc5d2c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9be460b7aeb8845ac44ae5eaf0dba097eaf7c8ca3eddeffe528ff039af2467c"

  strings:
    $s1 = "//if ([\"sash\", \"ofxu\", \"atojwi\", \"hulqasa\", \"cogovry\", \"oti\", \"zavivq\", \"jzofvi\", \"zynd\", \"dguho\", \"hetok\"" ascii
    $s2 = "ushexyxo9 = this[[\"ipvom\", [\"mvaw\", \"memve\", \"WSc\"][2], \"ije\", \"ebufhetb\", \"pydl\", \"vugbe\", \"sypvo\", \"odsejal" ascii
    $s3 = "ushexyxo9 = this[[\"ipvom\", [\"mvaw\", \"memve\", \"WSc\"][2], \"ije\", \"ebufhetb\", \"pydl\", \"vugbe\", \"sypvo\", \"odsejal" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}