rule TTP_XOR_QUAD_CurrentVersionRun_121f {
  strings:
    $key_121f = { 41 70 [2] 65 7e [2] 4e 52 [2] 60 70 [2] 74 6b [2] 7b 71 [2] 65 6c [2] 67 6d [2] 7c 6b [2] 60 6c [2] 7c 43 }

  condition:
    any of them
}