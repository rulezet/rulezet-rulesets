rule sig_20160518_f43f9c4fa34888f767fb76543a1f6fef {
  meta:
    description = "datamaliciousorder - file 20160518_f43f9c4fa34888f767fb76543a1f6fef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c3b3bdad5cc6cb1c95f33bee03323ab9861ad00288234487d97c64605281701"

  strings:
    $s1  = "var nunnery = [paleness, supersede,fighting,  \"\"+\".\"+(\"inquest\",\"initiated\",\"problem\",\"clothes\",\"suggests\",\"scand" ascii
    $s2  = "saucepan = ((\"connections\", \"round\", \"propecia\", \"mines\", \"sfCYqUOYEF\") + \"XeYsQvcuX\").recumbent2();" fullword ascii
    $s3  = "var futures=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".recumbent4())&&lesson[\"c3RhdHVz\".recumbent4()] +\"\"==\"MjAw\".rec" ascii
    $s4  = "var futures=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".recumbent4())&&lesson[\"c3RhdHVz\".recumbent4()] +\"\"==\"MjAw\".rec" ascii
    $s5  = "        conduct[(disposition + \"o\"+(\"woodsman\",\"twitter\",\"eugene\",\"versatile\",\"ravages\",\"surprised\",\"amazon\",\"d" ascii
    $s6  = "leaky = leaky+ nunnery.shift();" fullword ascii
    $s7  = "weasel = ((\"reflected\", \"crevice\", \"chancery\", \"crops\", \"EHcdiumyXxk\") + \"trLzLr\").recumbent2();" fullword ascii
    $s8  = "contraband(\"aHR0cDovLw==\".recumbent4()+\"\\u006E\\u006F\\u006C\\u0077\\u006F\\u006F\\u0064\\u006C\\u0061\\u006E\\u0064\"+\"\\u" ascii
    $s9  = "disposition = ((\"lingerie\", \"footage\", \"proffer\", \"spelling\", \"peaDRdNa\") + \"xcwDROtgyo\").recumbent2();" fullword ascii
    $s10 = "var membrane = nunnery.pop().split(\">\");" fullword ascii
    $s11 = "String.prototype.recumbent2 = function () {" fullword ascii
    $s12 = "String.prototype.recumbent = function () {" fullword ascii
    $s13 = "String.prototype.recumbent4 = function() {" fullword ascii
    $s14 = "var nunnery = [paleness, supersede,fighting,  \"\"+\".\"+(\"inquest\",\"initiated\",\"problem\",\"clothes\",\"suggests\",\"scand" ascii
    $s15 = "        var conduct = new providing(((\"unacceptable\",\"labeled\",\"wasteful\",\"posts\",\"prolific\",\"ranging\",\"turtle\",\"" ascii
    $s16 = "var providing = this[nunnery.shift()];" fullword ascii
    $s17 = "    physiology.acute = physiology.laity[\"c3Vic3RyaW5n\".recumbent4()](newark, memory);" fullword ascii
    $s18 = "contraband(\"aHR0cDovLw==\".recumbent4()+\"\\u006E\\u006F\\u006C\\u0077\\u006F\\u006F\\u0064\\u006C\\u0061\\u006E\\u0064\"+\"\\u" ascii
    $s19 = "var sloppy = implementing[nunnery.shift()](nunnery.shift());" fullword ascii
    $s20 = "giggling = \"b3Blbg==\".recumbent4();;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}