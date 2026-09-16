rule TTP_XOR_QUAD_CurrentVersionRun_24e2 {
  strings:
    $key_24e2 = { 77 8d [2] 53 83 [2] 78 af [2] 56 8d [2] 42 96 [2] 4d 8c [2] 53 91 [2] 51 90 [2] 4a 96 [2] 56 91 [2] 4a be }

  condition:
    any of them
}