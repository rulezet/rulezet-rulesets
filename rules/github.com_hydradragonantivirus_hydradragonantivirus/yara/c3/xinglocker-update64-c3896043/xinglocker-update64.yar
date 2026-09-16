import "pe"
rule xinglocker_update64 {
  meta:
    description = "xinglocker - file update64.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-10-07"
    hash1       = "47ff886d229a013d6e73d660a395f7b8e285342195680083eb96d64c052dd5f0"

  strings:
    $s1  = ">j=nAy;j;l;l;m;n;k;p;q;rFpFo;u;vBo;x;y<j<k<l<m<n@o<p<q<r<s<t<u<v<w<x<y=j=k=l=m=n=o=p=q=r=s=t=u=v=w=x=y>j>k>l>m>n>o>p>q>rCk>t>u>v" ascii
    $s2  = "?lAu>wGmCkCl;p?nFkCyGy;mCl>oDx9sGxCxCyHr<t?oHu<y@r=sClCkHvDtDuHn<p@m=jFoHkAqEmEnAw=wEvAo=l9v@kEyEwExEy>s>lBtFmEnFoBl>tFnBvElFuFv" ascii
    $s3  = "HnGtDyEpExFjAmEoAoFkEyEkEoEyAqAvErFpExFwFrFvFpFjBoEyFrEwEuBtFyFwEsFyBmGjCoCwDnCtCsCsCpCvCvCxGuDyCrCjDvDsCoDuCoDkHoDyDsDxDpCrDpDw" ascii
    $s4  = "Bw@oBrGr;vDqBoEpCoCp>qGvCrBq?s>oCwCxGm<u@pHm<r@u>wCoAuDrDsAs@u>oFtDyDyEj=l?qEyEpEoEpEq<y=yElEuExEwExEuFjFkCqEnBr>x:kBy>oEv:oDsFv" ascii
    $s5  = "BwBx;pCmCkClCm=vAkCnCqCr;l?vGm;w?sFpCwDjDkGwGwGyGr@o@u@nHsGsHm<y>kGxHq=u:rAt=xFk<sBkEqEr@jEsEuEvEw;p<oFkFkFlGj9pBs>uFlHo;n;o;nBj" ascii
    $s6  = "Bo>wGl9j9qGlGmGnBkEmFn<tCk?k;jCr?jCvGx9yGnEwDkHnHoDt@vHw;s:vHuHvDo@o<n=rAt:qDwGl9o9pGy<kFlHoHn=nApFs=qBuFtHt9oHsGtGs>uBmFt>lBp9s" ascii
    $s7  = ":oFoFlFj?k?l?m;vGx@qBr<t@sAk?k;nGpGuFy@j@k@l<tHw@lHwDn<nHnGp>yHv@v@x@yEs9tFsEmEw9xHoEyEk9l?sEtFmEvFjExEvExEy>j>rFw:w>mFj:jElBmFn" ascii
    $s8  = "FpDxFq?k=kCnGy;sCj:w>t>q>pGpCr?nGk;qFuBnBsAk?kHj<vElBmBrAt@m=nCsAkHkDyEjAs=uAn<nAw=m9qDvCk<o9wAn=x9sAy>m;yFjCk>oBw>uCtErBk>k9rBn" ascii
    $s9  = "FwFxBqEu;p>u:v:u:t:sCyFm;rBw<r?yBpExGyAo;w=tHlHnHoHpDy@mCoFxEuDn@x<tFy>yElExEyEr=wAy>u;v9k>w=mAyGk;x=pBuGs>tBrEw>wBmFx?v;sGtGn>w" ascii
    $s10 = ":w:x>qCoFx;wCqGr;o;p;q?jClHo?mFu?x@xFnEyExEw=q=l@k9y=n<v=y=t@m9o=x?x=u;t9w@u<j9n<k;l;k9v@j<s@m<r:j9tEq;n@o;l:uFs:k@l;q:v>pGw:j?n" ascii
    $s11 = "HoHuHkAjFkFjEpFqFpApAoGvEpFwEoEjElEyEuBjGoFwEkBnHqEnFrEyEtFyEsBvHyEuFkCnCwCqGkGrGoCyCsDuDwCuCqCjGwCyCkDnHkCjCpDtHoDyCmHpFnFjHuHv" ascii
    $s12 = "EsHv:y;j;k;l;m;nEyEn;q;r;s;t;u;vFmEv;y<j<k<l<m<n?qFn<q<r<s<t<u<v=yFy<y=j=k=l=m=nEwCq=q=r=s=t=u=vFqCy=y>j>k>l>m>n>o>p>q>r>s>t>u>v" ascii
    $s13 = "ByBwByCkCqCoCqCkCyCwCyCkCqCoCqCkCxCxCxDlDpDpDpDlDxDxDxDlDpDpDpDlDyDxDyEjEkElEmEnEoEpEqErEsEtEuEvEyExEyFjFkFlFmFnFoFpFqFrFsFtFuFv" ascii
    $s14 = "GoHuByCjCkClCmCnErFyFnFsEoExApElFsAjEtErFnDlDmDnFrEyEnEsFoFxBpFmEwEtBkCoDsCqEmEnCkCnClCpCxHyHuGlCrDpCtFjFkFlFmFnCpCqDoDuDpCrDxCy" ascii
    $s15 = "CqBxBpCjAnClFjCnCrCpCwCrCsCtCuCvGxCxGlDjHoDlHyDnHvDpHsDrHvDtAkDvDnDxBtEjDlElExEnEyEpEqErEsEtEuEvBkExApFjAkFlBjFnHkFpFqFrFsFtFuFv" ascii
    $s16 = ">p:yGp?l?k?l?m;k>pCp>nDtBp@yBw;u?w?xGtDj9o=r<uHy@x<tHtHn>wHt@t@v@w<pHvGnCoClAmEv9rFlCmDrEr<lDlAwAwAx@jAoBsFuBmBn:j>pGmAv:r;pDy:v" ascii
    $s17 = ";oGs;k<yDuAw@xAjCmGx>j=uCpHk>nGnAp@nGq?k>tHtDj?xHw@q>vDk<v?kEyDq<p@w=vArExGr9m<qEtBr<yAj=lEy?o@jEwExAq>o:kCpEuFuAl;j;nBjFpHj;u;y" ascii
    $s18 = ";k<t>y?j;wGy;j?oFy?x?q?r?s;lGjCnBl@u:w:n@k@l<uHyCw<xHlDr@pHxFm@v@w@x<q9uEwCpDuEr9rEtCmDvEo9k=uEn9jFtCuCj?xAq:oHjBoBp:v?r:v>tGyAk" ascii
    $s19 = "HwByAjCkDyCmDyDuDr;o;u;nCk?mDqErGoCp?pAvFoGlCpDv@r>tFmHr9o9o9nDn@v:lHy9o9k9l=uAs>jGpDx9v9r9t9uHm:rDo;k:j:kBsEuGu9j;w<r:r:s>lBp>k" ascii
    $s20 = "AwBp>v;nCkDw;j;rCw?yDuEvGkCl?lAjEsHxCq@sAoFpGuCmDnCjDpCyDk@s:qDvDo@wEl<r<o9l9m9n=wAwHx@w9n=lAp9k;k<t9y:jGx9q;o>l:o:p>yBo>o<x;uGm" ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and
    (pe.imphash() == "309f189ae3d618bfd1e08a8538aea73a" and (pe.exports("MkozycymwrxdxsUdddknsoskqjj") and pe.exports("NnzvpyfnjzgjflhXgbihjsjauma") and pe.exports("StartW") and pe.exports("WldxpodTdikvburej") and pe.exports("WqtzhacNqtdeAkecz") and pe.exports("startW")) or 8 of them)
}