rule TTP_XOR_QUAD_CurrentVersionRun_cbae {
  strings:
    $key_cbae = { 98 c1 [2] bc cf [2] 97 e3 [2] b9 c1 [2] ad da [2] a2 c0 [2] bc dd [2] be dc [2] a5 da [2] b9 dd [2] a5 f2 }

  condition:
    any of them
}