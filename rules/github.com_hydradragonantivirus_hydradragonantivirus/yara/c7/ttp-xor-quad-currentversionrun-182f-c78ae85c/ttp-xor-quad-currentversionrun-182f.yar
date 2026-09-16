rule TTP_XOR_QUAD_CurrentVersionRun_182f {
  strings:
    $key_182f = { 4b 40 [2] 6f 4e [2] 44 62 [2] 6a 40 [2] 7e 5b [2] 71 41 [2] 6f 5c [2] 6d 5d [2] 76 5b [2] 6a 5c [2] 76 73 }

  condition:
    any of them
}