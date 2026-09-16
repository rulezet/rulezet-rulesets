rule TTP_XOR_WriteProcessMemory_ca04 {
  strings:
    $key_ca04 = { 9d 76 [2] af 54 [2] a9 61 [2] 87 61 [2] b8 7d }

  condition:
    any of them
}