rule TTP_XOR_QUAD_CurrentVersionRun_61e2 {
  strings:
    $key_61e2 = { 32 8d [2] 16 83 [2] 3d af [2] 13 8d [2] 07 96 [2] 08 8c [2] 16 91 [2] 14 90 [2] 0f 96 [2] 13 91 [2] 0f be }

  condition:
    any of them
}