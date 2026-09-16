rule sig_20160516_9cdb59536ee31b0cb7cc3e1c39a6f259 {
  meta:
    description = "datamaliciousorder - file 20160516_9cdb59536ee31b0cb7cc3e1c39a6f259.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "543bc9c1407e229c992783e34a779f6beb9329f7054883584e108896d1064433"

  strings:
    $s1  = "weasel = ((\"cooperative\", \"curative\", \"adverted\", \"profit\", \"EdDtGMi\") + \"mASeXBeOB\").leonard2();" fullword ascii
    $s2  = "var vagrant =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".leonard4();" fullword ascii
    $s3  = "audio = ((\"trite\", \"democratic\", \"journalism\", \"thirtyfour\", \"sLLlSmdrgnq\") + \"dtzgKtNka\").leonard2();" fullword ascii
    $s4  = "fleece = fleece+ larceny.shift();" fullword ascii
    $s5  = "String.prototype.leonard4 = function() {" fullword ascii
    $s6  = "String.prototype.leonard2 = function () {" fullword ascii
    $s7  = "var flounder = larceny.pop().split(\"" fullword ascii
    $s8  = "String.prototype.leonard = function () {" fullword ascii
    $s9  = "            thracian[xanax]((\"jerky\",\"constraint\",\"G\" + weasel) + (\"volume\",\"combining\",\"norwegian\",\"persephone\"," ascii
    $s10 = "            thracian[xanax]((\"jerky\",\"constraint\",\"G\" + weasel) + (\"volume\",\"combining\",\"norwegian\",\"persephone\"," ascii
    $s11 = "var larceny = [crystalline, vagrant,april,  \"\"+\".\"+(\"vatican\",\"supplements\",\"nikon\",\"demise\",\"trickery\",\"childhoo" ascii
    $s12 = "var larceny = [crystalline, vagrant,april,  \"\"+\".\"+(\"vatican\",\"supplements\",\"nikon\",\"demise\",\"trickery\",\"childhoo" ascii
    $s13 = "var thracian = new airlines(flounder[0]);" fullword ascii
    $s14 = "function lyrics(swagger, intel) {" fullword ascii
    $s15 = "var crystalline = \"QWN0aXZlWE9iamVjdA==\".leonard4();" fullword ascii
    $s16 = "        chevy[(\"essay\",\"writing\",\"humanity\",\"postage\",\"elephant\",\"plane\",\"permanence\",\"w\")+\"ri\"+\"te\"](thraci" ascii
    $s17 = "var induction = {" fullword ascii
    $s18 = "var exotic = 0;" fullword ascii
    $s19 = "\",\"s\")+\"ubRt\"+(\"negotiations\",\"translators\",\"priced\",\"wonder\",\"civic\",\"digit\",\"barrister\",\"ri\")+\"ng\").rep" ascii
    $s20 = "var airlines = this[larceny.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}