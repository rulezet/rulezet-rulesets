rule TTP_XOR_QUAD_CurrentVersionRun_d0ee {
  strings:
    $key_d0ee = { 83 81 [2] a7 8f [2] 8c a3 [2] a2 81 [2] b6 9a [2] b9 80 [2] a7 9d [2] a5 9c [2] be 9a [2] a2 9d [2] be b2 }

  condition:
    any of them
}