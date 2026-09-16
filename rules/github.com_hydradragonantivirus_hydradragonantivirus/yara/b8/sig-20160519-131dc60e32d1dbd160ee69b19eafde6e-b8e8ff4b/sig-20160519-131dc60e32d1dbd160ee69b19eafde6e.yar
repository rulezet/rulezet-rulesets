rule sig_20160519_131dc60e32d1dbd160ee69b19eafde6e {
  meta:
    description = "datamaliciousorder - file 20160519_131dc60e32d1dbd160ee69b19eafde6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a14ac93acc31d186cb739b8df88129cc3c71f5aa77bdb2b8f9af65c1f80c685"

  strings:
    $s1  = "var indigent = [evaluate, ninetyfive,highlight,  \"\"+\".\"+(\"merchant\",\"fisher\",\"carve\",\"cacao\",\"screwed\",\"atlas\"," ascii
    $s2  = "var hogshead = new trouble(tempestuous[1]);" fullword ascii
    $s3  = "var tempestuous = indigent.pop().split(\">\");" fullword ascii
    $s4  = "var consults = new trouble(tempestuous[0]);" fullword ascii
    $s5  = "hogshead[indigent.shift()](mysterious, verse, true);" fullword ascii
    $s6  = "var linear = hogshead[indigent.shift()](indigent.shift());" fullword ascii
    $s7  = "weasel = ((\"vessels\", \"wedlock\", \"corks\", \"reprisal\", \"EdNAiWTsTJ\") + \"CdAjFcyvRb\").chemist2();" fullword ascii
    $s8  = "creator(\"aHR0cDovLw==\".chemist4()+\"\\u0069\\u006E\\u0067\\u0073\\u0074\\u0072\\u006F\\u0079\\u006D\\u0061\\u0073\\u0068\"+\"" ascii
    $s9  = "satiric = ((\"buffet\", \"symantec\", \"gossip\", \"notebook\", \"hampton\", \"sandwich\", \"sErMVEJOMea\") + \"vOOvjBy\").chemi" ascii
    $s10 = "mysterious = mysterious+ indigent.shift();" fullword ascii
    $s11 = "String.prototype.chemist4 = function() {" fullword ascii
    $s12 = "String.prototype.chemist2 = function () {" fullword ascii
    $s13 = "String.prototype.chemist = function () {" fullword ascii
    $s14 = "        athletics[(bradford + \"o\"+(\"allied\",\"statuette\",\"nucleus\",\"shanghai\",\"regards\",\"sussex\",\"slough\",\"recom" ascii
    $s15 = "        athletics[(bradford + \"o\"+(\"allied\",\"statuette\",\"nucleus\",\"shanghai\",\"regards\",\"sussex\",\"slough\",\"recom" ascii
    $s16 = "        var athletics = new trouble(((\"davies\",\"refugee\",\"rabid\",\"smart\",\"annul\",\"bottles\",\"asceticism\",\"myrtle\"" ascii
    $s17 = "for (var i in least){fortify = fortify.replace(i, least[i]);}" fullword ascii
    $s18 = "var trouble = this[indigent.shift()];" fullword ascii
    $s19 = "var apart = 0;" fullword ascii
    $s20 = "function creator(languor, distil) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}