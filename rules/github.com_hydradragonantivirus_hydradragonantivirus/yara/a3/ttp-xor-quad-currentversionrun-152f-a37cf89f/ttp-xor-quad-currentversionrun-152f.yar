rule TTP_XOR_QUAD_CurrentVersionRun_152f {
  strings:
    $key_152f = { 46 40 [2] 62 4e [2] 49 62 [2] 67 40 [2] 73 5b [2] 7c 41 [2] 62 5c [2] 60 5d [2] 7b 5b [2] 67 5c [2] 7b 73 }

  condition:
    any of them
}