rule TTP_XOR_QUAD_CurrentVersionRun_cba3 {
  strings:
    $key_cba3 = { 98 cc [2] bc c2 [2] 97 ee [2] b9 cc [2] ad d7 [2] a2 cd [2] bc d0 [2] be d1 [2] a5 d7 [2] b9 d0 [2] a5 ff }

  condition:
    any of them
}