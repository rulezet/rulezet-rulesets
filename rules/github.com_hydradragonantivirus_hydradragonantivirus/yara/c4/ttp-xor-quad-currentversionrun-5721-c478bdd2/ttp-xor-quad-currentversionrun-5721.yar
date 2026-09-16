rule TTP_XOR_QUAD_CurrentVersionRun_5721 {
  strings:
    $key_5721 = { 04 4e [2] 20 40 [2] 0b 6c [2] 25 4e [2] 31 55 [2] 3e 4f [2] 20 52 [2] 22 53 [2] 39 55 [2] 25 52 [2] 39 7d }

  condition:
    any of them
}