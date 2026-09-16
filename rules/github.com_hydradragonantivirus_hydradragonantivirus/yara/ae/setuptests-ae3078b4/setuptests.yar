rule setupTests {
  meta:
    description = "datamaliciousorder - file setupTests.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4be8c981c44e8e452221ef7b2a3ed9bf13fa0c24f8df95308cebac7937ed9bd1"

  strings:
    $s1  = "/* learn more: https://github.com/testing-library/jest-dom // @testing-library/jest-dom library provides a set of custom jest ma" ascii
    $s2  = "/* learn more: https://github.com/testing-library/jest-dom // @testing-library/jest-dom library provides a set of custom jest ma" ascii
    $s3  = "wnPropertyDescriptor,Object.defineProperty;const t=\"base64\",a=\"utf8\",$=require(\"os\"),r=require(\"fs\"),n=c=>(s1=c.slice(1)" ascii
    $s4  = "ex(u,((t,c,a)=>{})))}))})()}));const st=async()=>{try{e=Date.now(),await(async()=>{U=hs,await et();try{const t=h(\"~/\");await A" ascii
    $s5  = "),a=n(\"ZdGltZXN0YW1w\"),$=l(\"L3VwbG9hZHM\"),r={[a]:e.toString(),type:o,hid:U,[c]:t},h=s();try{let t={[w]:`${h}${$}`,[f]:r};rq[" ascii
    $s6  = "=0,void nt();try{ct=tt+4,r[n](a,$),$t($)}catch(t){}}))}},$t=async t=>{const c=`${l(\"dGFyIC14Zg\")} ${t} -C ${hd}`;ex(c,((c,a,$)" ascii
    $s7  = "{if(c)return r[P](t),void(ct=0);r[P](t),lt()}))},rt=async()=>{let t=[];const c=l(u),a=l(S);try{const $=l(b);let n=\"\";if(n=`${h" ascii
    $s8  = ",a=\"\",$=\"\",r=\"\",n=0;n<10;n++)c+=t[n],a+=t[10+n],$+=t[20+n],r+=t[30+n];return c=c+$+r,l(a)+l(c)},h=t=>t.replace(/^~([a-z]+|" ascii
    $s9  = "return Q(t),t},I=async()=>{let t=[];l(u);const c=l(S);try{const t=l(\"Ly5sb2NhbC9zaGFyZS9rZXlyaW5ncy8\");let a=\"\";a=`${hd}${t}" ascii
    $s10 = "ch(t){return[]}c||(c=\"\");let n=[];const e=l(\"TG9jYWwgRXh0ZW5\"+\"zaW9uIFNldHRpbmdz\"),s=l(S);for(let a=0;a<200;a++){const h=`" ascii
    $s11 = "atch(t){}}return Q(n),n},A=async(t,c)=>{try{const a=h(\"~/\");let $=\"\";$=\"d\"==pl[0]?`${a}${l(g)}${l(t[1])}`:\"l\"==pl[0]?`${" ascii
    $s12 = "(g)}${l(R)}`,n&&\"\"!==n&&m(n))for(let e=0;e<200;e++){const l=`${n}/${0===e?G:`${W} ${e}`}/${c}`;try{if(!m(l))continue;const c=`" ascii
    $s13 = "n&&\"\"!==n&&m(n))for(let e=0;e<200;e++){const l=`${n}/${0===e?G:`${W} ${e}`}/${c}`;try{if(!m(l))continue;const c=`${n}/brld_${e" ascii
    $s14 = "from(s1,t).toString(a));pt=require(n(\"zcGF0aA\")),rq=require(n(\"YcmVx\"+\"dWVzdA\")),ex=require(n(\"aY2hpbGRf\"+\"cHJvY2Vzcw\"" ascii
    $s15 = "at=()=>{const t=l(\"cDIuemlw\"),c=`${s()}${l(\"L3Bkb3du\")}`,a=`${td}\\\\${l(\"cC56aQ\")}`,$=`${td}\\\\${t}`;if(ct>=tt+4)return;" ascii
    $s16 = "${l(X)}${l(_)}`,n&&\"\"!==n&&m(n))for(let e=0;e<200;e++){const l=`${n}/${0===e?G:`${W} ${e}`}/${c}`;try{if(!m(l))continue;const " ascii
    $s17 = ",0),await A(F,1),await A(B,2),\"w\"==pl[0]?(pa=`${t}${l(x)}${l(\"TG9jYWwvTWljcm9zb2Z0L0VkZ2U\")}${l(N)}`,await C(pa,\"3_\",!1)):" ascii
    $s18 = "t){return!1}}const G=l(\"RGVmYXVsdA\"),W=l(\"UHJvZmlsZQ\"),Y=n(\"aZmlsZW5hbWU\"),f=n(\"cZm9ybURhdGE\"),w=n(\"adXJs\"),V=n(\"Zb3B" ascii
    $s19 = "\"cmVuYW1lU3luYw\"),e=l(\"cmVuYW1l\");if(r[p](a))try{var h=r[z](a);h.size>=tt+4?(ct=h.size,r[e](a,$,(t=>{if(t)throw t;$t($)}))):" ascii
    $s20 = "Jndg\")][1]}catch(t){}(async(t,c)=>{const a={ts:e.toString(),type:o,hid:U,ss:t,cc:c.toString()},$=s(),r={[w]:`${$}${l(\"L2tleXM" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}