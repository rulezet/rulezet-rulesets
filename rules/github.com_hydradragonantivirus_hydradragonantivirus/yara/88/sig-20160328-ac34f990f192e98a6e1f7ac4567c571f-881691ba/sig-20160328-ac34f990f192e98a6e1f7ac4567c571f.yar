rule sig_20160328_ac34f990f192e98a6e1f7ac4567c571f {
  meta:
    description = "datamaliciousorder - file 20160328_ac34f990f192e98a6e1f7ac4567c571f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "723bc0ac9dc9eefd111c475403ac33728b62b1d4918de95b8c02d94c6c8e662a"

  strings:
    $s1  = "eval(el(\"wrap%20%3D%20%28%22WScr%22%29%3B%20rmultiDash%20%3D%20%28%22jec%22%29%3B%20dispatch%20%3D%20%28%22sta%22%29%3B%20match" ascii
    $s2  = "ifModified[\"Sav\" + match + \"File\"](attrHandle, ((contents | 2) & (register - 36)));" fullword ascii
    $s3  = "animate[offset + \"ript\"][qsaError + \"ep\"](((uid | 5384) & (preexisting - 1727)));" fullword ascii
    $s4  = "bup(el(\"pipe%5Bwrap%20+%20%22ipt%22%5D%5Bpush_native%5D%28%28%28width*3*resolveValues*2*firing*2%29%7C%28getElementsByTagName%7" ascii
    $s5  = "ep\"]((29 * (gotoEnd * 3) + (Math.pow(iNoClone, 2) - implementation)));" fullword ascii
    $s6  = "bup(el(\"pipe%5Bwrap%20+%20%22ipt%22%5D%5Bpush_native%5D%28%28%28width*3*resolveValues*2*firing*2%29%7C%28getElementsByTagName%7" ascii
    $s7  = "while(err[scrollTo + \"dySta\" + time] != ((191, nodeType, 238, _load) - (11 + toggleClass))) username[\"WScr\" + parentsUntil][" ascii
    $s8  = "traditional = pipe = username = animate = isArrayLike.responseText();" fullword ascii
    $s9  = "ifModified[\"m\" + content + \"e\"] = ((84 / boolHook) & 3);" fullword ascii
    $s10 = "bup(el(\"disabled%20%3D%20%5B%22Msxml2%22%20+%20xhrFields%20+%20%22rXMLHT%22%20+%20related%2C%20%22Msxml%22%20+%20writable%20+%2" ascii
    $s11 = "if(err[dispatch + \"tus\"] == ((257 & documentElement) - 57)) {" fullword ascii
    $s12 = "err = username[namespace + \"pt\"][eventHandle + \"teObj\" + ontype](disabled[resolveWith]);" fullword ascii
    $s13 = "while(err[scrollTo + \"dySta\" + time] != ((191, nodeType, 238, _load) - (11 + toggleClass))) username[\"WScr\" + parentsUntil][" ascii
    $s14 = "bup(el(\"send%20%3D%20pipe%5B%22WScr%22%20+%20parentsUntil%5D%5B%22Crea%22%20+%20multipleContexts%20+%20%22bje%22%20+%20xhr%5D%2" ascii
    $s15 = "bup(el(\"send%20%3D%20pipe%5B%22WScr%22%20+%20parentsUntil%5D%5B%22Crea%22%20+%20multipleContexts%20+%20%22bje%22%20+%20xhr%5D%2" ascii
    $s16 = "function preFilter(setter, emptyGet, rclickable) {" fullword ascii
    $s17 = "send[matched + \"n\"](attrHandle);" fullword ascii
    $s18 = "ifModified[\"Wri\" + time](err[\"respo\" + anim + \"y\"]);" fullword ascii
    $s19 = "for(resolveWith = 0; resolveWith < disabled[\"l\" + success + \"th\"]; resolveWith++) {" fullword ascii
    $s20 = "function responseType(options, proxy, clone) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}