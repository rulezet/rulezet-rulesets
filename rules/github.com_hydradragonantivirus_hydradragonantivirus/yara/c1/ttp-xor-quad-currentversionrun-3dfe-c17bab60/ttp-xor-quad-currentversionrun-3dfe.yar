rule TTP_XOR_QUAD_CurrentVersionRun_3dfe {
  strings:
    $key_3dfe = { 6e 91 [2] 4a 9f [2] 61 b3 [2] 4f 91 [2] 5b 8a [2] 54 90 [2] 4a 8d [2] 48 8c [2] 53 8a [2] 4f 8d [2] 53 a2 }

  condition:
    any of them
}