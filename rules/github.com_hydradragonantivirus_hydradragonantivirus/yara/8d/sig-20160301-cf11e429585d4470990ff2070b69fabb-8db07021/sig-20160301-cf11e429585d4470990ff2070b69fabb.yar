rule sig_20160301_cf11e429585d4470990ff2070b69fabb {
  meta:
    description = "datamaliciousorder - file 20160301_cf11e429585d4470990ff2070b69fabb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7fd5b8dcd04909234235e9555c9b452a51bdb2ff9db6527af54ec2859ce9740"

  strings:
    $s1 = "while(anonymousDelegate[(\"\\u0063\\u006f\\u006f\\u0072d\\u0069\" + \"\\u006e\\u0061\" + \"t\\u0069\\u006fn\", \"\\u0062e\\u0061" ascii
    $s2 = "reservoirNumeral[(\"\\u0063\\u006f\\u006d\" + \"m\" + \"a\\u006e\\u0064\" + \"er\", \"as\\u0073\\u0069\" + \"\\u0073\\u0074\\u00" ascii
    $s3 = "2\" + \"ina\\u0074i\" + \"\\u006fn\", \"s\\u0074o\\u0072m\", function String.prototype.regulateModify() {" fullword ascii
    $s4 = "while(anonymousDelegate[(\"\\u0063\\u006f\\u006f\\u0072d\\u0069\" + \"\\u006e\\u0061\" + \"t\\u0069\\u006fn\", \"\\u0062e\\u0061" ascii
    $s5 = "airplaneModify = ((1 & 1), this);" fullword ascii
    $s6 = "} catch(vacancySubject) {};" fullword ascii

  condition:
    uint16(0) == 0x6961 and
    all of them
}