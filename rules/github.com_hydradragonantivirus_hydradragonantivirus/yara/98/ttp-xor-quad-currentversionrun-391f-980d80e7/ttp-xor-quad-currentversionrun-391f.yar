rule TTP_XOR_QUAD_CurrentVersionRun_391f {
  strings:
    $key_391f = { 6a 70 [2] 4e 7e [2] 65 52 [2] 4b 70 [2] 5f 6b [2] 50 71 [2] 4e 6c [2] 4c 6d [2] 57 6b [2] 4b 6c [2] 57 43 }

  condition:
    any of them
}