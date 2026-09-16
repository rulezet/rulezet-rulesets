rule sig_20160301_9e0e645d95482877e864c3615e0436e4 {
  meta:
    description = "datamaliciousorder - file 20160301_9e0e645d95482877e864c3615e0436e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9acad8f7dfaa05d885cc8df314f050b4f296553dcc1ffe53c6a2dbb5785c2db"

  strings:
    $s1 = "while(minusThesis[(\"r\" + \"\\u0065a\\u0064\" + \"yst\" + \"at\\u0065\")] < ((123, 182, 125, 35) - (23 ^ 8))) {" fullword ascii
    $s2 = "minusThesis[(\"\\u0061\\u0075t\" + \"o\\u0070il\\u006f\\u0074\", \"\\u0063\\u006fl\\u006c\" + \"ec\" + \"t\" + \"i\" + \"\\u006f" ascii
    $s3 = "minusThesis[(\"\\u0061\\u0075t\" + \"o\\u0070il\\u006f\\u0074\", \"\\u0063\\u006fl\\u006c\" + \"ec\" + \"t\" + \"i\" + \"\\u006f" ascii
    $s4 = "popularBusiness = (((0 | 0) ^ 1), this);" fullword ascii
    $s5 = "} catch(fileNavigate) {};" fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    all of them
}