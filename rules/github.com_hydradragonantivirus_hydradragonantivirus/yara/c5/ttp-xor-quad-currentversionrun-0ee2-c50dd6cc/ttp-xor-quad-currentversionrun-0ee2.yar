rule TTP_XOR_QUAD_CurrentVersionRun_0ee2 {
  strings:
    $key_0ee2 = { 5d 8d [2] 79 83 [2] 52 af [2] 7c 8d [2] 68 96 [2] 67 8c [2] 79 91 [2] 7b 90 [2] 60 96 [2] 7c 91 [2] 60 be }

  condition:
    any of them
}