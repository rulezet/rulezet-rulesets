rule TTP_XOR_WriteProcessMemory_dbed {
  strings:
    $key_dbed = { 8c 9f [2] be bd [2] b8 88 [2] 96 88 [2] a9 94 }

  condition:
    any of them
}