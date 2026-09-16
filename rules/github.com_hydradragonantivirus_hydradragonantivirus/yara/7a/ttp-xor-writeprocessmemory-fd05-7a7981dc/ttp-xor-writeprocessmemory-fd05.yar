rule TTP_XOR_WriteProcessMemory_fd05 {
  strings:
    $key_fd05 = { aa 77 [2] 98 55 [2] 9e 60 [2] b0 60 [2] 8f 7c }

  condition:
    any of them
}