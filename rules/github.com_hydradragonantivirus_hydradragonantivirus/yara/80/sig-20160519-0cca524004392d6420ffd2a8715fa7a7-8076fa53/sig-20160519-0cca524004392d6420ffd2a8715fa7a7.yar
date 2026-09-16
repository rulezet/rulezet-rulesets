rule sig_20160519_0cca524004392d6420ffd2a8715fa7a7 {
  meta:
    description = "datamaliciousorder - file 20160519_0cca524004392d6420ffd2a8715fa7a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56618c423de1aa1e099077972680c372474d4a2555d4f3985d05070d93f544ee"

  strings:
    $s1  = "var approval=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".styles4())&&overwhelm[\"c3RhdHVz\".styles4()] +\"\"==\"MjAw\".style" ascii
    $s2  = "var approval=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".styles4())&&overwhelm[\"c3RhdHVz\".styles4()] +\"\"==\"MjAw\".style" ascii
    $s3  = "var abbeys = [participate, fighting,requirement,  \"\"+\".\"+(\"tudor\",\"stratified\",\"aviation\",\"baptize\",\"unchallenged\"" ascii
    $s4  = "weasel = ((\"penetration\", \"cereal\", \"struct\", \"breviary\", \"EJgdyqVAQWNm\") + \"yekjOVoHxe\").styles2();" fullword ascii
    $s5  = "brand(\"aHR0cDovLw==\".styles4()+\"\\u0061\\u0070\\u0061\\u0072\\u0074\\u006D\\u0061\\u006E\\u0069\\u0070\\u0072\\u0065\\u006B" ascii
    $s6  = "sophistry = sophistry+ abbeys.shift();" fullword ascii
    $s7  = "String.prototype.styles = function () {" fullword ascii
    $s8  = "String.prototype.styles2 = function () {" fullword ascii
    $s9  = "String.prototype.styles4 = function() {" fullword ascii
    $s10 = "var wayward = abbeys.pop().split(\">\");" fullword ascii
    $s11 = "    knowing.temperatures = knowing.asbestos[\"c3Vic3RyaW5n\".styles4()](tacked, steam);" fullword ascii
    $s12 = "    return knowing.temperatures;" fullword ascii
    $s13 = "brand(\"aHR0cDovLw==\".styles4()+\"\\u0061\\u0070\\u0061\\u0072\\u0074\\u006D\\u0061\\u006E\\u0069\\u0070\\u0072\\u0065\\u006B" ascii
    $s14 = "var participate = \"QWmemberN0aXZmemberlWE9iamembermVjdA=member=\".styles4();" fullword ascii
    $s15 = "for (var i in flower){obtrude = obtrude.replace(i, flower[i]);}" fullword ascii
    $s16 = "        var vacillation = new resort(((\"dumbfounded\",\"consulting\",\"matins\",\"headquarters\",\"tryst\",\"lending\",\"reprie" ascii
    $s17 = "        var vacillation = new resort(((\"dumbfounded\",\"consulting\",\"matins\",\"headquarters\",\"tryst\",\"lending\",\"reprie" ascii
    $s18 = "purveyor = ((\"fervor\", \"punic\", \"arcadia\", \"repulsion\", \"pDlOIPzi\") + \"MoqxnCLtAij\").styles2();" fullword ascii
    $s19 = "function brand(acceleration, paraguay) {" fullword ascii
    $s20 = "var fighting =\"RXhwYW5memberkRW52aXmemberJvbm1lbnRTdHJmemberpbmdz\".styles4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}