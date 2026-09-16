rule sig_20160301_e4e2d01df62219fa331150f97859680c {
  meta:
    description = "datamaliciousorder - file 20160301_e4e2d01df62219fa331150f97859680c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fe9a50a27ba940494e5820445950cf57f13ea6c0056572c73d746d00ec3b4f"

  strings:
    $s1 = "reputationStandard = microphoneBit[(\"c\\u006fmme\" + \"\\u006e\\u0074\", function String.prototype.refrigeratorSatellite() {" fullword ascii
    $s2 = "microphoneBit = (((42 / 42) + 0), this);" fullword ascii
    $s3 = "while(technicalSkeleton[(\"agen\\u0074\", \"r\" + \"ead\" + \"y\\u0073\\u0074\" + \"a\" + \"\\u0074e\")] < (0 + (202, 91, 166, 4" ascii
    $s4 = "} catch(contractBit) {};" fullword ascii

  condition:
    uint16(0) == 0x696d and
    all of them
}