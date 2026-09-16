rule sig_20160330_82af54656fe1f257c6b764c963d4095b {
  meta:
    description = "datamaliciousorder - file 20160330_82af54656fe1f257c6b764c963d4095b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e243061f5d06c8bed294de31c0f03b5960086e00ca10dd2f35649da6230c204"

  strings:
    $s1  = "eval(unescape([\"wrapMap&20&3D&20&2821&29&2C&20class2type&20&3D&20&28&22WScr&22&29&2C&20nodeNameSelector&20&3D&20&28&\", \"22Msx" ascii
    $s2  = "if(support[async + \"s\"] == ((pageX * 17) - (wrapMap | 16))) {" fullword ascii
    $s3  = "fast(\"parentNode&20&3D&20&5BnodeNameSelector&20+&20&22l2.Ser&22&20+&20getter&20+&20&22XMLHTT&22&20+&20marginLeft&2C&20&22Msxm&2" ascii
    $s4  = "support[\"se\" + getElementsByClassName]();" fullword ascii
    $s5  = "support = doc[opt + \"t\"][inspect + \"ateOb\" + padding](parentNode[preDispatch]);" fullword ascii
    $s6  = "fast(\"parentNode&20&3D&20&5BnodeNameSelector&20+&20&22l2.Ser&22&20+&20getter&20+&20&22XMLHTT&22&20+&20marginLeft&2C&20&22Msxm&2" ascii
    $s7  = "fast(\"attributes&20&3D&20interval&5B&22Expand&22&20+&20finalValue&20+&20&22ronm&22&20+&20animate&20+&20&22tri&22&20+&20doAnimat" ascii
    $s8  = "fast(\"returnValue&28&22htt&22&20+&20tokenCache&20+&20&22digit&22&20+&20pixelMarginRightVal&20+&20&22etinga&22&20+&20href&20+&20" ascii
    $s9  = "callbackContext[version + \"yp\" + prefilterOrFactory] = ((190, startTime, 1) / (addEventListener / 8));" fullword ascii
    $s10 = "fast(\"support&5B&22op&22&20+&20prefilterOrFactory&20+&20&22n&22&5D&28fail&20+&20&22T&22&2C&20seed&20+&20&22//di&22&20+&20delega" ascii
    $s11 = "fast(\"support&5B&22op&22&20+&20prefilterOrFactory&20+&20&22n&22&5D&28fail&20+&20&22T&22&2C&20seed&20+&20&22//di&22&20+&20delega" ascii
    $s12 = "function removeEvent(ifModified, name, setRequestHeader) {" fullword ascii
    $s13 = "function fontWeight(getAll, tick, needsContext) {" fullword ascii
    $s14 = "fast(\"while&20&28support&5B&22ready&22&20+&20diff&5D&20&21&3D&20&28Callbacks*&282*fixInput&29&29&29&20status&5B&22WScr&22&20+&2" ascii
    $s15 = "interval[\"R\" + iterator](attributes);" fullword ascii
    $s16 = "function keys(handlerQueue, optgroup) {" fullword ascii
    $s17 = "fast(\"interval&20&3D&20isArrayLike&5B&22WSc&22&20+&20replaceWith&5D&5B&22Creat&22&20+&20blur&20+&20&22ject&22&5D&28isDefaultPre" ascii
    $s18 = "callbackContext[attrHandle](support[\"respo\" + eventPath + \"ody\"]);" fullword ascii
    $s19 = "fast(\"isArrayLike&5Bclass2type&20+&20&22ipt&22&5D&5BtabIndex&5D&28&28&28exports+183&29*&28Callbacks*5&29+&28id&7C66&29&29&29&3B" ascii
    $s20 = "fast(\"isArrayLike&5Bclass2type&20+&20&22ipt&22&5D&5BtabIndex&5D&28&28&28exports+183&29*&28Callbacks*5&29+&28id&7C66&29&29&29&3B" ascii

  condition:
    uint16(0) == 0x7461 and
    8 of them
}