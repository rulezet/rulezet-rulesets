rule TTP_XOR_QUAD_CurrentVersionRun_4919 {
  strings:
    $key_4919 = { 1a 76 [2] 3e 78 [2] 15 54 [2] 3b 76 [2] 2f 6d [2] 20 77 [2] 3e 6a [2] 3c 6b [2] 27 6d [2] 3b 6a [2] 27 45 }

  condition:
    any of them
}