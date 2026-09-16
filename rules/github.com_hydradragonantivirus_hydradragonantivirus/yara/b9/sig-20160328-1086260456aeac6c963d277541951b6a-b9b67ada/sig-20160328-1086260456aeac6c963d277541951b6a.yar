rule sig_20160328_1086260456aeac6c963d277541951b6a {
  meta:
    description = "datamaliciousorder - file 20160328_1086260456aeac6c963d277541951b6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a28e6bdca6e182ac4e1f6802c631dd730b69d1b10f5c645234974014466e0a13"

  strings:
    $s1  = "eval(complete(\"var%20checkNonElements%20%3D%20%28%22/np%22%29%3Bbooleans%20%3D%20%28%22.s%22%29%3Bvar%20rhash%20%3D%20%28%22/%2" ascii
    $s2  = "fired[mozMatchesSelector + \"od\" + getJSON] = ((2511 / parse) / (Math.pow(14, prepend) - 169));" fullword ascii
    $s3  = "  while(related[token + \"tate\"] != ((checkOn | 4) | (prepend * 2))) rmouseEvent[onload + \"pt\"][createPositionalPseudo + \"ee" ascii
    $s4  = "  rtypenamespace(complete(\"version%20%3D%20%5B%22Msxml2%22%20+%20preFilter%20+%20%22rverXM%22%20+%20callbackInverse%20+%20%22P." ascii
    $s5  = "  rtypenamespace(complete(\"send%28val%20+%20%22/npo%22%20+%20ajaxHandleResponses%20+%20%22mr.ru/%22%20+%20cssPrefixes%20+%20%22" ascii
    $s6  = "scripts = rmouseEvent = context = tweens = nextUntil.xhrSupported();" fullword ascii
    $s7  = "  rtypenamespace(complete(\"related%5Bclosest%20+%20%22p%22%20+%20getJSON%20+%20%22n%22%5D%28lock%20+%20%22T%22%2C%20tick%20+%20" ascii
    $s8  = "  rtypenamespace(complete(\"related%5Bclosest%20+%20%22p%22%20+%20getJSON%20+%20%22n%22%5D%28lock%20+%20%22T%22%2C%20tick%20+%20" ascii
    $s9  = "  if(related[preventDefault + \"us\"] == ((write - 118) * (prepend))) {" fullword ascii
    $s10 = "  while(related[token + \"tate\"] != ((checkOn | 4) | (prepend * 2))) rmouseEvent[onload + \"pt\"][createPositionalPseudo + \"ee" ascii
    $s11 = "  for(tag = (0 / (prepend * 2 * prepend * 2)); tag < version[clientLeft + \"h\"]; tag++) {" fullword ascii
    $s12 = "  rtypenamespace(complete(\"related%20%3D%20rmouseEvent%5BnodeValue%20+%20%22rip%22%20+%20dataPriv%5D%5B%22Cre%22%20+%20newUnmat" ascii
    $s13 = "function combinator(dirrunsUnique, actualDisplay) {" fullword ascii
    $s14 = "  rtypenamespace(complete(\"cached%20%3D%20disconnectedMatch%5B%22Exp%22%20+%20cssText%20+%20%22vironm%22%20+%20arg%20+%20%22Str" ascii
    $s15 = "  rtypenamespace(complete(\"fired%20%3D%20context%5B%22WScri%22%20+%20onreadystatechange%5D%5B%22Cre%22%20+%20ajaxPrefilter%20+%" ascii
    $s16 = "  rtypenamespace(complete(\"rmouseEvent%5B%22WScri%22%20+%20onreadystatechange%5D%5B%22Sleep%22%5D%28%28%28803*_removeData+4%29+" ascii
    $s17 = "  rtypenamespace(complete(\"fired%20%3D%20context%5B%22WScri%22%20+%20onreadystatechange%5D%5B%22Cre%22%20+%20ajaxPrefilter%20+%" ascii
    $s18 = "  rtypenamespace(complete(\"disconnectedMatch%20%3D%20tweens%5B%22WScri%22%20+%20onreadystatechange%5D%5B%22Creat%22%20+%20cssPr" ascii
    $s19 = "  rtypenamespace(complete(\"rmouseEvent%5B%22WScri%22%20+%20onreadystatechange%5D%5B%22Sleep%22%5D%28%28%28803*_removeData+4%29+" ascii
    $s20 = "  rtypenamespace(complete(\"disconnectedMatch%20%3D%20tweens%5B%22WScri%22%20+%20onreadystatechange%5D%5B%22Creat%22%20+%20cssPr" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}