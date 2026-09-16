rule infected_09_02_18_shell_solus {
  meta:
    description = "shell1 - file solus.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-02"
    hash1       = "99f3776c10f35ebcf6729e346ee2d655aabbdebc494757fc3c6f8a5880f91dbc"

  strings:
    $s1  = "pdD1cJ2cobnVsbCxudWxsLCIxIix0aGlzLnBhcmFtLnZhbHVlKTtyZXR1cm4gZmFsc2U7XCc+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN" ascii  
    $s2  = "lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW4+UG9zaXhfZ2V0cHd1aWQgKCJSZWFkIiAvZXRjL3Bhc3N3ZCk8L3NwYW4" ascii  
    $s3  = "wdGZVMVJTUlVGTkxHZGxkSEJ5YjNSdllubHVZVzFsS0NkMFkzQW5LU2tnZkh3Z1pHbGxJQ0pEWVc1MElHTnlaV0YwWlNCemIyTnJaWFJjYmlJN0RRcHpaWFJ6YjJOcmI" ascii  
    $s4  = "eval(\"?>\".base64_decode(\"PD9waHANCg0KDQokY29sb3IgPSAiI0ZFQ0QwMSI7DQokZGVmYXVsdF9hY3Rpb24gPSAnRmlsZXNNYW4nOw0KQGRlZmluZSgnU0VM" ascii
    $s5  = "xS1RzTkNpQWdJQ0IzYUdsc1pTZ3hLU0I3RFFvZ0lDQWdJQ0FnSUdNOVlXTmpaWEIwS0hNc01Dd3dLVHNOQ2lBZ0lDQWdJQ0FnWkhWd01paGpMREFwT3cwS0lDQWdJQ0F" ascii  
    $s6  = "uYW1lJ10uIjwvdGQ+PHRkPjxhIGhyZWY9J3N5bS9yb290L2hvbWUvIi4kdXNlclsnbmFtZSddLiIvcHVibGljX2h0bWwnIHRhcmdldD0nX2JsYW5rJz5zeW1saW5rIDw" ascii  
    $s7  = "+PHRkPiIuJGNvdW50KysuIjwvdGQ+PHRkPjxhIHRhcmdldD0nX2JsYW5rJyBocmVmPWh0dHA6Ly8iLiRkLicvPicuJGRkdC4nIDwvYT48L3RkPjx0ZD4nLiR1c2VyWyd" ascii  
    $s8  = "0ck91dHB1dCcpLnN0eWxlLmRpc3BsYXk9Jyc7ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0ck91dHB1dCcpLmlubmVySFRNTD0nIi5hZGRjc2xhc2hlcyhodG1sc3B" ascii  
    $s9  = "rYng+PC90ZD48dGQ+PGEgaHJlZj0jIG9uY2xpY2s9IicuKCgkZlsndHlwZSddPT0nZmlsZScpPydnKFwnRmlsZXNUb29sc1wnLG51bGwsXCcnLnVybGVuY29kZSgkZls" ascii  
    $s10 = "vU1U1QlJFUlNYMEZPV1NrN0RRb2dJQ0FnWW1sdVpDaHpMQ0FvYzNSeWRXTjBJSE52WTJ0aFpHUnlJQ29wSm5Jc0lEQjRNVEFwT3cwS0lDQWdJR3hwYzNSbGJpaHpMQ0E" ascii  
    $s11 = "XOXdaVzRnVTFSRVJWSlNMQ0krSmtOUFRrNGlPdzBLQ1FsbGVHVmpJQ1JUU0VWTVRDQjhmQ0JrYVdVZ2NISnBiblFnUTA5T1RpQWlRMkZ1ZENCbGVHVmpkWFJsSUNSVFN" ascii  
    $s12 = "2YWx1ZSk7aWYodGhpcy5hamF4LmNoZWNrZWQpe2EobnVsbCxudWxsLHRoaXMuY21kLnZhbHVlKTt9ZWxzZXtnKG51bGwsbnVsbCx0aGlzLmNtZC52YWx1ZSk7fSByZXR" ascii  
    $s13 = "uY2xpY2s9ImcoXCdQaHBcJyxudWxsLG51bGwsXCdpbmZvXCcpIj5bIHBocGluZm8gXTwvYT48YnIgLz46ICcuKCRHTE9CQUxTWydzYWZlX21vZGUnXT8nPGZvbnQgY29" ascii  
    $s14 = "9Y2htb2QgdmFsdWU9Iicuc3Vic3RyKHNwcmludGYoJyVvJywgZmlsZXBlcm1zKCRfUE9TVFsncDEnXSkpLC00KS4nIj48aW5wdXQgdHlwZT1zdWJtaXQgdmFsdWU9Ij4" ascii  
    $s15 = "yZ2dMV2tpT3cwS2FXWWdLRUJCVWtkV0lEd2dNU2tnZXlCbGVHbDBLREVwT3lCOURRcDFjMlVnVTI5amEyVjBPdzBLYzI5amEyVjBLRk1zSmxCR1gwbE9SVlFzSmxOUFE" ascii  
    $s16 = "DQWlQaVpUVDBOTFJWUWlLVHNOQ205d1pXNG9VMVJFUlZKU0xDQWlQaVpUVDBOTFJWUWlLVHNOQ25ONWMzUmxiU2duTDJKcGJpOXphQ0F0YVNjcE93MEtZMnh2YzJVb1U" ascii  
    $s17 = "pNDQudGlueXBpYy5jb20vMTE3NW5rai5naWYiIGlkPSJsb2dvIiBoZWlnaHQ9Ijc1JSIgd2lkdGg9IjkwJSIvPjwvZGl2PjxociBzdHlsZT0ibWFyZ2luOiAtNXB4IDE" ascii  
    $s18 = "JbnAiIHR5cGU9dGV4dCBuYW1lPWMgdmFsdWU9IicuaHRtbHNwZWNpYWxjaGFycygkR0xPQkFMU1snY3dkJ10pLiciPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4" ascii  
    $s19 = "ocC5pbmlcJyxudWxsKSI+fCBQSFAuSU5JIHwgPC9hPjxhIGhyZWY9IyBvbmNsaWNrPSJnKG51bGwsbnVsbCxudWxsLFwnaW5pXCcpIj58IC5odGFjY2VzcyhNb2QpIHw" ascii  
    $s20 = "5SUhCYk16QmRPdzBLSUNBZ0lITjBjblZqZENCemIyTnJZV1JrY2w5cGJpQnlPdzBLSUNBZ0lHUmhaVzF2YmlneExEQXBPdzBLSUNBZ0lITWdQU0J6YjJOclpYUW9RVVp" ascii  

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 400KB and
      (8 of them)
    ) or (all of them)
}