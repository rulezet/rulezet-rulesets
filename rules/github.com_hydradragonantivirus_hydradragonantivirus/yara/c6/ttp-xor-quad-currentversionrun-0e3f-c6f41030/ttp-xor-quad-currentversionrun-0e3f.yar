rule TTP_XOR_QUAD_CurrentVersionRun_0e3f {
  strings:
    $key_0e3f = { 5d 50 [2] 79 5e [2] 52 72 [2] 7c 50 [2] 68 4b [2] 67 51 [2] 79 4c [2] 7b 4d [2] 60 4b [2] 7c 4c [2] 60 63 }

  condition:
    any of them
}