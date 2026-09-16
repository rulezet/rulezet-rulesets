rule sig_20160313_5aa017bb3b5c3a2b8acbe6dae38e01f4 {
  meta:
    description = "datamaliciousorder - file 20160313_5aa017bb3b5c3a2b8acbe6dae38e01f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b1568e019d72ae68b5bfdbb1e28b5f22c81e3e088a47dc93c6241805ed32457"

  strings:
    $s1  = "rwhitespace[compiled + \"en\"](originalOptions + \"T\", setRequestHeader + \"p:/\" + when + \"oguyf\" + parseJSON + \"m/70.\" + " ascii
    $s2  = "rwhitespace[compiled + \"en\"](originalOptions + \"T\", setRequestHeader + \"p:/\" + when + \"oguyf\" + parseJSON + \"m/70.\" + " ascii
    $s3  = "parts = \"WSc\", originalOptions = \"GE\", getScript = \"ep\", node = \"Res\", id = \".XMLH\";" fullword ascii
    $s4  = "postFinder = siblingCheck[\"Cre\" + fnOut + \"bject\"](parts + \"ript.\" + sort + \"ll\");" fullword ascii
    $s5  = ") * ((((disconnectedMatch - 13) + lastModified) * ((70 / clone) + (0 | lastModified))))) == (((101 + defer) / (49 & prop)) & ((1" ascii
    $s6  = "setDocument = \"ject\", stopQueue = \"t\", setRequestHeader = \"htt\", defaultDisplay = 49, firstElementChild = (function rattri" ascii
    $s7  = "setDocument = \"ject\", stopQueue = \"t\", setRequestHeader = \"htt\", defaultDisplay = 49, firstElementChild = (function rattri" ascii
    $s8  = "rwhitespace = this[createPositionalPseudo + \"ipt\"][elemLang + \"eObj\" + augmentWidthOrHeight](\"MSXML2\" + id + \"TTP\");" fullword ascii
    $s9  = "cssProps = this[unwrap + \"pt\"][elemLang + \"eOb\" + setDocument](\"ADOD\" + innerText + \"trea\" + attr);" fullword ascii
    $s10 = "var addCombinator = this;" fullword ascii
    $s11 = "return addCombinator;" fullword ascii
    $s12 = "function modified() {" fullword ascii
    $s13 = "self();" fullword ascii
    $s14 = "function self() {" fullword ascii
    $s15 = "function expand() {" fullword ascii
    $s16 = "expand();" fullword ascii
    $s17 = "function options() {" fullword ascii
    $s18 = "hidden = rattributeQuotes.globalEval();" fullword ascii
    $s19 = "disconnectedMatch = (function rattributeQuotes() {}, 15)," fullword ascii
    $s20 = "rpseudo = 20, html = 3142, define = \"exe\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}