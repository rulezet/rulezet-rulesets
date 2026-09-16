rule TTP_XOR_QUAD_CurrentVersionRun_384f {
  strings:
    $key_384f = { 6b 20 [2] 4f 2e [2] 64 02 [2] 4a 20 [2] 5e 3b [2] 51 21 [2] 4f 3c [2] 4d 3d [2] 56 3b [2] 4a 3c [2] 56 13 }

  condition:
    any of them
}