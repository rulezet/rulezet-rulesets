rule TTP_XOR_QUAD_CurrentVersionRun_157f {
  strings:
    $key_157f = { 46 10 [2] 62 1e [2] 49 32 [2] 67 10 [2] 73 0b [2] 7c 11 [2] 62 0c [2] 60 0d [2] 7b 0b [2] 67 0c [2] 7b 23 }

  condition:
    any of them
}