rule sig_20160301_0b95fb3d438af0165226cc41fe60df71 {
  meta:
    description = "datamaliciousorder - file 20160301_0b95fb3d438af0165226cc41fe60df71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f948cff9f5ae16da00e6c02fb451e37faf84c8463905466ea013d16913c4fbc0"

  strings:
    $s1 = "while (meridianDollar[(\"\\u0070\" + \"\\u0072\\u006fv\\u0069\" + \"n\\u0063e\", \"a\" + \"d\" + \"\\u0065q\\u0075a\\u0074\" + " ascii
    $s2 = "migrateAvenue = (((1 * 1) & (1 & 1)), this);" fullword ascii
    $s3 = "migrateAvenue[(\"\\u0069m\\u0061g\\u0065\", \"c\" + \"a\\u006d\" + \"er\" + \"\\u0061\", function String.prototype.depotMomentum" ascii
    $s4 = "while (meridianDollar[(\"\\u0070\" + \"\\u0072\\u006fv\\u0069\" + \"n\\u0063e\", \"a\" + \"d\" + \"\\u0065q\\u0075a\\u0074\" + " ascii
    $s5 = "} catch (operatorAccumulator) {};" fullword ascii

  condition:
    uint16(0) == 0x696d and
    all of them
}