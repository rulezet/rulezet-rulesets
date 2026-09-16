rule TTP_XOR_QUAD_CurrentVersionRun_341f {
  strings:
    $key_341f = { 67 70 [2] 43 7e [2] 68 52 [2] 46 70 [2] 52 6b [2] 5d 71 [2] 43 6c [2] 41 6d [2] 5a 6b [2] 46 6c [2] 5a 43 }

  condition:
    any of them
}