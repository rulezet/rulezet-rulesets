rule sig_20160517_c7121f9d32aab793dd35fa1b360994e4 {
  meta:
    description = "datamaliciousorder - file 20160517_c7121f9d32aab793dd35fa1b360994e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ba7002f60ea8a15286dda2ddb00e9f38ab4435a5bd1002009f31d9eb8965669"

  strings:
    $s1  = "        greece[(transformation + \"o\"+(\"freely\",\"twoedged\",\"scissors\",\"effective\",\"ecommerce\",\"eddie\",\"peevish\"," ascii
    $s2  = "var ambiguity=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sickle4())&&detailed[\"c3RhdHVz\".sickle4()] +\"\"==\"MjAw\".sickl" ascii
    $s3  = "var ambiguity=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sickle4())&&detailed[\"c3RhdHVz\".sickle4()] +\"\"==\"MjAw\".sickl" ascii
    $s4  = "cleaving = cleaving+ harrow.shift();" fullword ascii
    $s5  = "weasel = ((\"incredulous\", \"prism\", \"diversity\", \"apollo\", \"EfMFungTRFNV\") + \"CHdvlz\").sickle2();" fullword ascii
    $s6  = "denouement(\"aHR0cDovLw==\".sickle4()+\"\\u0063\\u0070\\u006C\\u006E\\u007A\\u002E\\u0063\\u006F\\u006D\"+\"\\u002F\\u0037\\u003" ascii
    $s7  = "transformation = ((\"bonfire\", \"misunderstand\", \"marie\", \"gully\", \"pVySQXi\") + \"OauksAK\").sickle2();" fullword ascii
    $s8  = "pedigree = ((\"usurer\", \"besiege\", \"trainer\", \"symphony\", \"stjYOiWjRyCR\") + \"tilxkOR\").sickle2();" fullword ascii
    $s9  = "var configuration = showtimes[harrow.shift()](harrow.shift());" fullword ascii
    $s10 = "        greece[(transformation + \"o\"+(\"freely\",\"twoedged\",\"scissors\",\"effective\",\"ecommerce\",\"eddie\",\"peevish\"," ascii
    $s11 = "String.prototype.sickle4 = function() {" fullword ascii
    $s12 = "m\",\"A\")+(\"hilarity\",\"comparison\",\"laptops\",\"shred\",\"pounds\",\"cornell\",\"loves\",\"inorganic\",\"SEOO\")+\"DB\"+(" ascii
    $s13 = "String.prototype.sickle = function () {" fullword ascii
    $s14 = "String.prototype.sickle2 = function () {" fullword ascii
    $s15 = "        var cleaving = configuration + \"/\" + aggravation ;" fullword ascii
    $s16 = "var harrow = [enterprises, plenty,calvary,  \"\"+\".\"+(\"careful\",\"springs\",\"charts\",\"cameo\",\"precocious\",\"audio\",\"" ascii
    $s17 = "var plenty =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".sickle4();" fullword ascii
    $s18 = "otential\",\"riding\",\"innocent\",\"potency\",\"08\"), pedigree)] = 0;" fullword ascii
    $s19 = "function denouement(bowman, aggravation) {" fullword ascii
    $s20 = "photography = \"b3Blbg==\".sickle4();;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}