rule TTP_XOR_QUAD_CurrentVersionRun_ed21 {
  strings:
    $key_ed21 = { be 4e [2] 9a 40 [2] b1 6c [2] 9f 4e [2] 8b 55 [2] 84 4f [2] 9a 52 [2] 98 53 [2] 83 55 [2] 9f 52 [2] 83 7d }

  condition:
    any of them
}