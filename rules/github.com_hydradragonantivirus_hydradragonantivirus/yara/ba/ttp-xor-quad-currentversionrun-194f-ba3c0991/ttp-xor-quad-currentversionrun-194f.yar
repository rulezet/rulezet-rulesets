rule TTP_XOR_QUAD_CurrentVersionRun_194f {
  strings:
    $key_194f = { 4a 20 [2] 6e 2e [2] 45 02 [2] 6b 20 [2] 7f 3b [2] 70 21 [2] 6e 3c [2] 6c 3d [2] 77 3b [2] 6b 3c [2] 77 13 }

  condition:
    any of them
}