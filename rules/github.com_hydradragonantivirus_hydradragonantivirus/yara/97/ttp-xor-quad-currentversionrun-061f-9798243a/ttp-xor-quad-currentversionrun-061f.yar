rule TTP_XOR_QUAD_CurrentVersionRun_061f {
  strings:
    $key_061f = { 55 70 [2] 71 7e [2] 5a 52 [2] 74 70 [2] 60 6b [2] 6f 71 [2] 71 6c [2] 73 6d [2] 68 6b [2] 74 6c [2] 68 43 }

  condition:
    any of them
}