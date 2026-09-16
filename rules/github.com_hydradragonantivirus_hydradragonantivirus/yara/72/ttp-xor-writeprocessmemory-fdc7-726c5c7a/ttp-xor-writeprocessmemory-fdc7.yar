rule TTP_XOR_WriteProcessMemory_fdc7 {
  strings:
    $key_fdc7 = { aa b5 [2] 98 97 [2] 9e a2 [2] b0 a2 [2] 8f be }

  condition:
    any of them
}