rule sig_20160518_20b9744f9447a77e7ac28097ac10b457 {
  meta:
    description = "datamaliciousorder - file 20160518_20b9744f9447a77e7ac28097ac10b457.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90733c45694939eaecda9ec256c449e7de90868ff79b23b35e448af4125dda34"

  strings:
    $s1  = "var resolved = [bridesmaid, gloves,denunciation,  \"\"+\".\"+(\"confirmation\",\"banking\",\"science\",\"casey\",\"surprised\"," ascii
    $s2  = "oncoming = ((\"pseudonym\", \"mythological\", \"intermittent\", \"horde\", \"pOczMSBn\") + \"QTNKAoTiYUv\").newport2();" fullword ascii
    $s3  = "var orchestral=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".newport4())&&adroitly[\"c3RhdHVz\".newport4()] +\"\"==\"MjAw\".ne" ascii
    $s4  = "var orchestral=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".newport4())&&adroitly[\"c3RhdHVz\".newport4()] +\"\"==\"MjAw\".ne" ascii
    $s5  = "        amphitheatre[\"d3JpdGU=\".newport4()](adroitly[(\"prologue\",\"indeterminate\",\"yamaha\",\"eliminated\",\"seaweed\",\"h" ascii
    $s6  = "senile(\"aHR0cDovLw==\".newport4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u0061\\u006E" ascii
    $s7  = "weasel = ((\"assessed\", \"asked\", \"administered\", \"woolly\", \"ECTqTTqRolV\") + \"ylkOWN\").newport2();" fullword ascii
    $s8  = "String.prototype.newport2 = function () {" fullword ascii
    $s9  = "String.prototype.newport = function () {" fullword ascii
    $s10 = "String.prototype.newport4 = function() {" fullword ascii
    $s11 = "        amphitheatre[\"d3JpdGU=\".newport4()](adroitly[(\"prologue\",\"indeterminate\",\"yamaha\",\"eliminated\",\"seaweed\",\"h" ascii
    $s12 = "arrangement = arrangement+ resolved.shift();" fullword ascii
    $s13 = "        amphitheatre[(oncoming + \"o\"+(\"shown\",\"successfully\",\"sierra\",\"speeches\",\"routine\",\"influences\",\"ulcer\"," ascii
    $s14 = "var bridesmaid = \"QWplanetaryN0aXZplanetarylWE9iaplanetarymVjdA=planetary=\".newport4();" fullword ascii
    $s15 = "casque = ((\"keith\", \"jackass\", \"otter\", \"inventive\", \"syayEwYH\") + \"cBIQJbdItch\").newport2();" fullword ascii
    $s16 = "senile(\"aHR0cDovLw==\".newport4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u0061\\u006E" ascii
    $s17 = "var instant = resolved.pop().split(\">\");" fullword ascii
    $s18 = "var denunciation =\"JVplanetaryRFTVplanetaryAl\".newport4();" fullword ascii
    $s19 = "        amphitheatre[(oncoming + \"o\"+(\"shown\",\"successfully\",\"sierra\",\"speeches\",\"routine\",\"influences\",\"ulcer\"," ascii
    $s20 = "            adroitly[concentrations]((\"surpass\",\"importune\",\"G\" + weasel) + (\"fundamentals\",\"generates\",\"academical\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}