rule TTP_XOR_QUAD_CurrentVersionRun_61e3 {
  strings:
    $key_61e3 = { 32 8c [2] 16 82 [2] 3d ae [2] 13 8c [2] 07 97 [2] 08 8d [2] 16 90 [2] 14 91 [2] 0f 97 [2] 13 90 [2] 0f bf }

  condition:
    any of them
}