rule sig_20160518_c72126b7de86022bc7a638a06454a0e2 {
  meta:
    description = "datamaliciousorder - file 20160518_c72126b7de86022bc7a638a06454a0e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "905989f4edac50b81d19d5fcdd32d02ea6a254d561e2f7e069e8318272fe080f"

  strings:
    $s1  = "var madhouse = [kenneth, legate,cartoon,  \"\"+\".\"+(\"sports\",\"competing\",\"wallow\",\"clicks\",\"emails\",\"resolutions\"," ascii
    $s2  = "var circa=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".insects4())&&abashed[\"c3RhdHVz\".insects4()] +\"\"==\"MjAw\".insects4" ascii
    $s3  = "var circa=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".insects4())&&abashed[\"c3RhdHVz\".insects4()] +\"\"==\"MjAw\".insects4" ascii
    $s4  = "var downloads = this[madhouse.shift()];" fullword ascii
    $s5  = "var nostril = new downloads(samples[1]);" fullword ascii
    $s6  = "var abashed = new downloads(samples[0]);" fullword ascii
    $s7  = "for (var i in pathology){decisions = decisions.replace(i, pathology[i]);}" fullword ascii
    $s8  = "var pathology = {" fullword ascii
    $s9  = "abridgment = abridgment+ madhouse.shift();" fullword ascii
    $s10 = "weasel = ((\"sulphide\", \"flippant\", \"suicide\", \"strike\", \"ESxzfElRLS\") + \"wJfAzChr\").insects2();" fullword ascii
    $s11 = "fallacy(\"aHR0cDovLw==\".insects4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u0061\\u006" ascii
    $s12 = "String.prototype.insects4 = function() {" fullword ascii
    $s13 = "String.prototype.insects2 = function () {" fullword ascii
    $s14 = "String.prototype.insects = function () {" fullword ascii
    $s15 = "var madhouse = [kenneth, legate,cartoon,  \"\"+\".\"+(\"sports\",\"competing\",\"wallow\",\"clicks\",\"emails\",\"resolutions\"," ascii
    $s16 = "        var detailed = new downloads(((\"whilst\",\"construct\",\"paint\",\"absented\",\"equations\",\"gayest\",\"confidentialit" ascii
    $s17 = "        var detailed = new downloads(((\"whilst\",\"construct\",\"paint\",\"absented\",\"equations\",\"gayest\",\"confidentialit" ascii
    $s18 = "  scope = [];" fullword ascii
    $s19 = "juicy = ((\"andromeda\", \"camera\", \"ashley\", \"narrative\", \"srUHCUhU\") + \"AhivLdxdzq\").insects2();" fullword ascii
    $s20 = "fallacy(\"aHR0cDovLw==\".insects4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u0061\\u006" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}