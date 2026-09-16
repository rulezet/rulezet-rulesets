rule TTP_XOR_QUAD_CurrentVersionRun_342f {
  strings:
    $key_342f = { 67 40 [2] 43 4e [2] 68 62 [2] 46 40 [2] 52 5b [2] 5d 41 [2] 43 5c [2] 41 5d [2] 5a 5b [2] 46 5c [2] 5a 73 }

  condition:
    any of them
}