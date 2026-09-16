rule coms_openssl {
  meta:
    author = "@tylabs"

  strings:
    $s1 = ".\\ssl\\ssl_lib.c"
    $s2 = ".\\ssl\\ssl_sess.c"
    $s3 = "part of OpenSSL"

  condition:
    all of them
}