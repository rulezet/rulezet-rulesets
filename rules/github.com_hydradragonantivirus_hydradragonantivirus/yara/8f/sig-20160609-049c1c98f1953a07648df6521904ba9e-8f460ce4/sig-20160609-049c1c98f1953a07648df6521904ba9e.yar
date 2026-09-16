rule sig_20160609_049c1c98f1953a07648df6521904ba9e {
  meta:
    description = "datamaliciousorder - file 20160609_049c1c98f1953a07648df6521904ba9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15f346a1889df38e4caa8541b80cd5f71b1cf72ea5bb3ac1c0f472481105ee9c"

  strings:
    $s1  = ")(\"var u0b={\\'L4\\':\\\"shyt\\\",\\'f6\\':\\\"fdnd\\\",\\'m6\\':\\\"wer8\\\",\\'t0\\':\\\"6dfj\\\",\\'V9\\':\\\"hdjk\\\",\\'G9" ascii
    $s2  = ";R8y<p8y.length;){if(p8y.charAt(R8y)!=\"`\")U8y+=p8y.charAt(R8y++);else{if(p8y.charAt(R8y+1)!=\"`\"){var r8y=x8y(p8y.charAt(R8y+" ascii
    $s3  = ";R8y<p8y.length;){if(p8y.charAt(R8y)!=\"`\")U8y+=p8y.charAt(R8y++);else{if(p8y.charAt(R8y+1)!=\"`\"){var r8y=x8y(p8y.charAt(R8y+" ascii
    $s4  = "else{U8y+=\"`\";R8y+=2;}" fullword ascii
    $s5  = "return d8y;}" fullword ascii
    $s6  = "1` M fy\\\",\\'s3\\':\\\"fhfh\\\",\\'a1y\\':false,\\'V2\\':\\\"dskj\\\",\\'f3y\\':\\\"935j\\\",\\'K4y\\':\\\"5364\\\",\\'Y5X\\':" ascii
    $s7  = "eval((function(p8y){for(var U8y=\"\",R8y=0,x8y=function(p8y,V8y){for(var d8y=0,D8y=0;D8y<V8y;D8y++){d8y*=96;var M8y=p8y.charCode" ascii
    $s8  = "return U8y;}" fullword ascii
    $s9  = "eval((function(p8y){for(var U8y=\"\",R8y=0,x8y=function(p8y,V8y){for(var d8y=0,D8y=0;D8y<V8y;D8y++){d8y*=96;var M8y=p8y.charCode" ascii
    $s10 = "7X),u0b.d,u0b.D);}catch(O){};};xa[` R S` I!x0` X!F0` \\\"!M6)]();};if(dn==u0b.d){ld=i;break;};}catch(O){};};}\"));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}