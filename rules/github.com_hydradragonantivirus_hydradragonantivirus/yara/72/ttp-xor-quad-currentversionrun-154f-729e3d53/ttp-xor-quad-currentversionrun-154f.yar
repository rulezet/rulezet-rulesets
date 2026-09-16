rule TTP_XOR_QUAD_CurrentVersionRun_154f {
  strings:
    $key_154f = { 46 20 [2] 62 2e [2] 49 02 [2] 67 20 [2] 73 3b [2] 7c 21 [2] 62 3c [2] 60 3d [2] 7b 3b [2] 67 3c [2] 7b 13 }

  condition:
    any of them
}