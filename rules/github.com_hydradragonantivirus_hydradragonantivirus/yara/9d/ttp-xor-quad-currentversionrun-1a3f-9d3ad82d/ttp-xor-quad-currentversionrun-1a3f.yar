rule TTP_XOR_QUAD_CurrentVersionRun_1a3f {
  strings:
    $key_1a3f = { 49 50 [2] 6d 5e [2] 46 72 [2] 68 50 [2] 7c 4b [2] 73 51 [2] 6d 4c [2] 6f 4d [2] 74 4b [2] 68 4c [2] 74 63 }

  condition:
    any of them
}